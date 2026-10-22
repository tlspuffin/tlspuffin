#[test]
fn postgres_connection_and_query_succeed() {
    let database_url = std::env::var("SPP_POSTGRES_URL").unwrap_or_else(|_| {
        "host=127.0.0.1 port=5432 user=control_component password=control_component dbname=control_component"
            .to_string()
    });
    let mut client = postgres::Client::connect(&database_url, postgres::NoTls)
        .expect("should connect to the PostgreSQL database");
    let row = client
        .query_one("SELECT 1", &[])
        .expect("should execute SELECT 1");
    assert_eq!(row.get::<_, i32>(0), 1);
}
