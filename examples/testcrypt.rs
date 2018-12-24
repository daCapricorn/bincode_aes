#[macro_use]
extern crate serde_derive;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Entity {
    x: f32,
    y: f32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct World(Vec<Entity>);

fn main() {
    let key = bincode_aes::random_key();
    let bc = bincode_aes::with_key(key);

    let world = World(vec![Entity { x: 0.0, y: 4.0 }, Entity { x: 10.0, y: 20.5 }]);

    let mut encoded: Vec<u8> = bc.serialize(&world).unwrap();

    let decoded: World = bc.deserialize(&mut encoded).unwrap();

    assert_eq!(world, decoded);
}
