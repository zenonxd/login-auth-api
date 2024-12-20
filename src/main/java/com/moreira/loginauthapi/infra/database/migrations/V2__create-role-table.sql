CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE tb_role (

    /*
    get_random_uuid é uma função
    de uma extensão do Postgres
    onde iremos instalar depois.
    Ela irá gerar uma random UUID
    */
    id VARCHAR DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR(30) NOT NULL UNIQUE
);