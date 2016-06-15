set rowcount @rows;
select subject_id, cohort_start_date, cohort_end_date
from
    (select subject_id, cohort_start_date, cohort_end_date,
            gc.concept_name as gender,
            cast(floor((year(cohort_start_date) - year_of_birth) / 10) * 10 as varchar(5)) + '-' +
                cast(floor((year(cohort_start_date) - year_of_birth) / 10 + 1) * 10 - 1 as varchar(5)) as age,
            (select round(count(*), - floor(log10(abs(count(*) + 0.01)))) 
             from @tableQualifier.condition_occurrence co 
             where co.person_id = c.subject_id) as conditions,
            (select round(count(*), - floor(log10(abs(count(*) + 0.01))))
             from @tableQualifier.drug_exposure de 
             where de.person_id = c.subject_id) as drugs
    from @tableQualifier.cohort c
    join @tableQualifier.person p on c.subject_id = p.person_id
    join @tableQualifier.concept gc on p.gender_concept_id = gc.concept_id
    where cohort_definition_id = @cohortDefinitionId
    ) cohort_people
/*whereclause*/
