use secmatch::evaluator::transform_response;
use secir::template::Transform;

fn main() {
    let data = b"test".to_vec();
    let result = transform_response(
        data,
        &[
            Transform::Base64Decode, // Will fail
            Transform::HexDecode,    // Will fail
        ],
    );
    println!("After Base64 and Hex: {:?}", result);
}
