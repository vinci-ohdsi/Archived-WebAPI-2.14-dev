package org.ohdsi.webapi.shiro.filters;

import static org.ohdsi.webapi.shiro.management.AtlasSecurity.AUTH_CLIENT_ATTRIBUTE;
import static org.ohdsi.webapi.shiro.management.AtlasSecurity.PERMISSIONS_ATTRIBUTE;
import static org.ohdsi.webapi.shiro.management.AtlasSecurity.TOKEN_ATTRIBUTE;

import io.buji.pac4j.subject.Pac4jPrincipal;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.util.WebUtils;
import org.ohdsi.webapi.Constants;
import org.ohdsi.webapi.shiro.Entities.UserPrincipal;
import org.ohdsi.webapi.shiro.PermissionManager;
import org.ohdsi.webapi.shiro.TokenManager;
import org.ohdsi.webapi.util.UserUtils;
import org.pac4j.core.profile.CommonProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author gennadiy.anisimov
 */
public class UpdateAccessTokenFilter extends AdviceFilter {
  private final Logger logger = LoggerFactory.getLogger(UpdateAccessTokenFilter.class);

  private final PermissionManager authorizer;
  private final int tokenExpirationIntervalInSeconds;
  private final Set<String> defaultRoles;
  private final String onFailRedirectUrl;

  public UpdateAccessTokenFilter(
          PermissionManager authorizer,
          Set<String> defaultRoles,
          int tokenExpirationIntervalInSeconds,
          String onFailRedirectUrl) {
    this.authorizer = authorizer;
    this.tokenExpirationIntervalInSeconds = tokenExpirationIntervalInSeconds;
    this.defaultRoles = defaultRoles;
    this.onFailRedirectUrl = onFailRedirectUrl;
  }
  
  @Override
  protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
    if (!SecurityUtils.getSubject().isAuthenticated()) {
      WebUtils.toHttp(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      return false;
    }

    String login;
    String name = null;
    String jwt = null;
    final PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
    Object principal = principals.getPrimaryPrincipal();
    
    if (principal instanceof Pac4jPrincipal) {
      login = ((Pac4jPrincipal)principal).getProfile().getEmail();
      name = ((Pac4jPrincipal)principal).getProfile().getDisplayName();
      
      /**
      * for CAS login
      */
      ShiroHttpServletRequest requestShiro = (ShiroHttpServletRequest) request;
      HttpSession shiroSession = requestShiro.getSession();
      if (login == null && shiroSession.getAttribute(CasHandleFilter.CONST_CAS_AUTHN) != null   // TODO - can we use something similar to flag that it is a Fence/oid with teamProject? For now we're just fishing it out from the request parameters itself
              && ((String) shiroSession.getAttribute(CasHandleFilter.CONST_CAS_AUTHN)).equalsIgnoreCase("true")) {
              login = ((Pac4jPrincipal) principal).getProfile().getId();
      }
            
      if (login == null) {
        // user doesn't provide email - send empty token
        request.setAttribute(TOKEN_ATTRIBUTE, "");
        // stop session to make logout of OAuth users possible
        Session session = SecurityUtils.getSubject().getSession(false);
        if (session != null) {
          session.stop();
        }

        HttpServletResponse httpResponse = WebUtils.toHttp(response);

        URI oauthFailURI = getOAuthFailUri();
        httpResponse.sendRedirect(oauthFailURI.toString());
        return false;
      }

      CommonProfile profile = (((Pac4jPrincipal) principal).getProfile());
      if (Objects.nonNull(profile)) {
        String clientName = profile.getClientName();
        request.setAttribute(AUTH_CLIENT_ATTRIBUTE, clientName);
      }
    } else     if (principal instanceof Principal) {
      login = ((Principal) principal).getName();
    } else if (principal instanceof UserPrincipal){
      login = ((UserPrincipal) principal).getUsername();
      name = ((UserPrincipal) principal).getName();
    } else if (principal instanceof String) {
      login = (String)principal;
    } else {
      throw new Exception("Unknown type of principal");
    }

    login = UserUtils.toLowerCase(login);

    // stop session to make logout of OAuth users possible
    Session session = SecurityUtils.getSubject().getSession(false);
    if (session != null) {
      session.stop();
    }

    if (jwt == null) { // dead check...jwt is always null...
      if (name == null) {
        name = login;
      }
      try {
        // TODO - remove all teamProject roles at start of login (find this place...OR add a new "remove teamproject" filter)...

        boolean resetRoles = false;
        // check if teamProject is part of the request:
        String teamProjectRole = extractTeamProjectFromRequestParameters(request);
        Set<String> newUserRoles = new HashSet<String>();
        if (teamProjectRole != null) {
          // add teamProject as a role in the newUserRoles list:
          newUserRoles.add(teamProjectRole);
          resetRoles = true;
          // TODO - double check with Arborist if this role has really been granted to the user....
        }
        this.authorizer.registerUser(login, name, defaultRoles, newUserRoles, resetRoles);
        
      } catch (Exception e) {
        WebUtils.toHttp(response).setHeader("x-auth-error", e.getMessage());
        throw new Exception(e);
      }

      String sessionId = (String) request.getAttribute(Constants.SESSION_ID);
      if (sessionId == null) {
        final String token = TokenManager.extractToken(request);
        if (token != null) {
          sessionId = (String) TokenManager.getBody(token).get(Constants.SESSION_ID);
        }
      }

      Date expiration = this.getExpirationDate(this.tokenExpirationIntervalInSeconds);
      jwt = TokenManager.createJsonWebToken(login, sessionId, expiration);
    }

    request.setAttribute(TOKEN_ATTRIBUTE, jwt);
    Collection<String> permissions = this.authorizer.getAuthorizationInfo(login).getStringPermissions();
    request.setAttribute(PERMISSIONS_ATTRIBUTE, StringUtils.join(permissions, "|"));
    return true;
  }

  private URI getOAuthFailUri() throws URISyntaxException {
    return getFailUri("oauth_error_email");
  }

  private URI getFailUri(String failFragment) throws URISyntaxException {

    URI oauthFailURI = new URI(onFailRedirectUrl);
    String fragment = oauthFailURI.getFragment();
    StringBuilder sbFragment = new StringBuilder();
    if(fragment == null) {
      sbFragment.append(failFragment).append("/");
    } else if(fragment.endsWith("/")){
      sbFragment.append(fragment).append(failFragment).append("/");
    } else {
      sbFragment.append(fragment).append("/").append(failFragment).append("/");
    }
    return UriBuilder.fromUri(oauthFailURI).fragment(sbFragment.toString()).build();
  }

  private Date getExpirationDate(final int expirationIntervalInSeconds) {
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.SECOND, expirationIntervalInSeconds);
    return calendar.getTime();
  }


  private String extractTeamProjectFromRequestParameters(ServletRequest request) {
    logger.debug("Looking for redirectUrl....");
    String[] redirectUrlParams = getParameterValues(request, "redirectUrl");
    if (redirectUrlParams != null) {
      logger.debug("Parameter redirectUrl found. Checking if it contains teamproject....");
      // teamProject will be in first one in this case...as only parameter:
      String firstParameter = redirectUrlParams[0].toLowerCase();
      if (firstParameter.contains("teamproject=")) {
        String teamProject = firstParameter.split("teamproject=")[1];
        logger.debug("Found teamproject: {}", teamProject);
        return teamProject;
      }
    } else {
      // try to find "teamproject" param in url itself (there will be no redirectUrl if user session is still valid):
      String[] teamProjectParams = getParameterValues(request, "teamproject");
      if (teamProjectParams != null) {
        logger.debug("Parameter teamproject found. Parsing....");
        String teamProject = teamProjectParams[0].toLowerCase();
        logger.debug("Found teamproject: {}", teamProject);
        return teamProject;
      }
    }
    logger.debug("Found NO teamproject.");
    return null;
  }

  private String[] getParameterValues(ServletRequest request, String parameterName) {
    // Get the parameters
    logger.debug("Looking for parameter with name: {} ...", parameterName);
    Enumeration<String> paramNames = request.getParameterNames();
    while(paramNames.hasMoreElements()) {
        String paramName = paramNames.nextElement();
        logger.debug("Parameter name: {}", paramName);
        if (paramName.equals(parameterName)) {
          String[] paramValues = request.getParameterValues(paramName);
          return paramValues;
        }
    }
    logger.debug("Found NO parameter with name: {}", parameterName);
    return null;
  }
}
