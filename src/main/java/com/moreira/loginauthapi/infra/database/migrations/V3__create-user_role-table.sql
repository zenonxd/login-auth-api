CREATE TABLE user_roles (
    user_id VARCHAR NOT NULL,
    role_id VARCHAR NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES tb_user(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES tb_role(id) ON DELETE CASCADE
);