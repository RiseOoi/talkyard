
delete from spam_check_queue3;

alter table spam_check_queue3 add column posted_to_page_id int;
alter table spam_check_queue3 add column page_published_at timestamp;
alter table spam_check_queue3 add column user_name varchar;  -- rename to author_name
alter table spam_check_queue3 add column user_email varchar;  -- rename to author_email_addr
alter table spam_check_queue3 add column user_trust_level int;
alter table spam_check_queue3 add column user_url varchar;
alter table spam_check_queue3 add column text_to_spam_check varchar;
alter table spam_check_queue3 add column language varchar;

alter table spam_check_queue3 add constraint spamcheckqueue_c_username_len check (
    length(user_name) between 1 and 10100);

alter table spam_check_queue3 add constraint spamcheckqueue_c_useremailaddr_len check (
    length(user_email) between 1 and 10100);

alter table spam_check_queue3 add constraint spamcheckqueue_c_userurl_len check (
    length(user_url) between 1 and 10100);

alter table spam_check_queue3 add constraint spamcheckqueue_c_userurl_len check (
    length(text_to_spam_check) between 1 and 10100);


alter table spam_check_queue3 add column results_at timestamp;
alter table spam_check_queue3 add column results_json jsonb;
alter table spam_check_queue3 add column results_text varchar;
alter table spam_check_queue3 add column num_is_spam_results int;
alter table spam_check_queue3 add column num_not_spam_results int;
alter table spam_check_queue3 add column human_says_is_spam bool;
alter table spam_check_queue3 add column is_misclassified boolean; -- dupl data, for simpler lookup
alter table spam_check_queue3 add column misclassifications_reported_at timestamp;

alter table spam_check_queue3 add constraint spamcheckqueue_c_results_null_eq check (
    (results_at is null) = (results_json is null) and
    (results_at is null) = (results_text is null) and
    (results_at is null) = (num_is_spam_results is null) and
    (results_at is null) = (num_not_spam_results is null));

alter table spam_check_queue3 add constraint spamcheckqueue_c_ismiscl_null check (
    (results_at is not null and human_says_is_spam is not null) = (is_misclassified is not null));

alter table spam_check_queue3 add constraint spamcheckqueue_c_results_before_report_miscl check (
    ((results_json is not null) and (human_says_is_spam is not null))
    or (misclassifications_reported_at is null));

alter table spam_check_queue3 add constraint spamcheckqueue_c_resultsjson_len check (
    pg_column_size(results_json) between 2 and 10100);

alter table spam_check_queue3 add constraint spamcheckqueue_c_resultstext_len check (
    length(results_text) between 1 and 10100);

alter table spam_check_queue3 drop constraint scq_site_post__p;
alter table spam_check_queue3 add constraint scq_site_postid_revnr__p primary key (
    site_id, post_id, post_rev_nr);

create index spamcheckqueue_next_miscl_i on spam_check_queue3 (results_at asc)
  where
    is_misclassified is not null and
    misclassifications_reported_at is null;

