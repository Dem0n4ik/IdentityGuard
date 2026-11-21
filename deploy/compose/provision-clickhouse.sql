CREATE USER IF NOT EXISTS ig_hunt_reader IDENTIFIED WITH sha256_password BY {reader_password:String};
ALTER USER ig_hunt_reader IDENTIFIED WITH sha256_password BY {reader_password:String};
GRANT SELECT ON identityguard.events TO ig_hunt_reader;
