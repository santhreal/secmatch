use urlencoding::decode;
fn main() {
    let result = decode("test").unwrap().into_owned().into_bytes();
    println!("{:?}", result);
}
