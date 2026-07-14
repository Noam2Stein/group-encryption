use wincode::{SchemaRead, SchemaWrite};

#[derive(SchemaWrite, SchemaRead)]
pub enum Request {
    ReturnNumber(u32),
}

#[derive(SchemaWrite, SchemaRead)]
pub enum Response {
    Number(u32),
}
