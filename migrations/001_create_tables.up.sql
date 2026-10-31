CREATE TABLE IF NOT EXISTS threats (
    md5             VARCHAR(32)     PRIMARY KEY,
    name            VARCHAR(255)    NOT NULL,
    type            VARCHAR(12)     NOT NULL CHECK (type IN ('trojan', 'virus', 'worm', 'ransomware', 'spyware', 'other', 'unknown')),
    level           VARCHAR(10)     NOT NULL CHECK (level IN ('low', 'medium', 'high', 'critical', 'unknown')),
    status          VARCHAR(14)     NOT NULL DEFAULT 'suspected' CHECK (status IN ('suspected', 'confirmed', 'false_positive')),
    description     TEXT,
    source          VARCHAR(255),
    first_seen_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_md5 CHECK (md5 ~ '^[a-fA-F0-9]{32}$'),
    CONSTRAINT valid_name CHECK (char_length(name) BETWEEN 3 AND 255 AND name ~ '\S'),
    CONSTRAINT valid_description CHECK (char_length(description) <= 2000)
);

