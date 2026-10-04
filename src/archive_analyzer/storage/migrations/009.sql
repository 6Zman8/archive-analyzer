-- Reset is an appended HOLD action; keep all earlier decisions for audit.
CREATE TABLE review_reset_actions (
    review_action_id INTEGER PRIMARY KEY REFERENCES review_actions(id)
);
