use extism::{host_fn, Plugin};
host_fn!(dns_resolve(input: String) -> String { Ok("[]".to_string()) });
fn main() {
    let f1 = dns_resolve::builder().build(); // or something?
}
