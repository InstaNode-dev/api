-- Remove the trial column from teams. Per policy memory
-- project_no_trial_pay_day_one.md the platform has no trial; this column
-- was a vestige of an earlier billing model.
ALTER TABLE teams DROP COLUMN IF EXISTS trial_ends_at;
