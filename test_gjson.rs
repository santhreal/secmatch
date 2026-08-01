fn main() {
    let json = r#"{"name": {"first": "Tom", "last": "Anderson"}, "age": 37, "children": ["Sara", "Alex", "Jack"], "friends": [{"first": "James", "last": "Murphy"}, {"first": "Colin", "last": "Trotter"}]}"#;
    let res = gjson::get(json, "name.last");
    println!("name.last='{}'", res.str());
    let res = gjson::get(json, "friends.#.first");
    println!("friends.#.first='{}'", res.str());
    let res = gjson::get(json, "children");
    println!("children='{}'", res.str());
}
