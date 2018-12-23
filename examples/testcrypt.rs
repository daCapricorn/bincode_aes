#[macro_use]
extern crate serde_derive;
extern crate rand;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Entity {
    x: f32,
    y: f32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct World(Vec<Entity>);

fn main() {
    //let iv = bincode_aes::random_iv();
    //let mut bc = bincode_aes::new();
    let key = bincode_aes::random_key();
    let iv = bincode_aes::random_iv();
    let mut bc = bincode_aes::with_params(key, iv);

    let world = World(vec![Entity { x: 0.0, y: 4.0 }, Entity { x: 10.0, y: 20.5 }]);

    let mut encoded: Vec<u8> = bc.serialize(&world).unwrap();

    let decoded: World = bc.deserialize(&mut encoded).unwrap();

    assert_eq!(world, decoded);
}
