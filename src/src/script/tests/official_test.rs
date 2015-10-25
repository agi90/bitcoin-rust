use rustc_serialize::json::Json;
use std::io::Read;

use hyper::Client;
use hyper::header::Connection;

pub struct Tester;

impl Tester {
    pub fn test<F> (callback: F) -> i32
    where F: Fn(&str, &str, &str) -> bool {
        let data = Tester::download_test();
        let json = Tester::get_array(Json::from_str(&data).unwrap());

        let mut passed = 0;
        let mut failed = vec![];
        for test in json {
            let mut test_array = Tester::get_array(test);
            test_array.reverse();

            // test_array.len() == 1 is a comment
            if test_array.len() > 1 {
                let script_sig = Tester::get_string(test_array.pop().unwrap());
                let script_pub_key = Tester::get_string(test_array.pop().unwrap());
                // let flags = Tester::get_string(test_array.pop().unwrap());

                if callback(&script_sig, &script_pub_key, "") {
                    passed += 1;
                } else {
                    failed.push((script_sig, script_pub_key));
                }
            }
            print!("passed={}\n", passed);
        }

        print!("failed tests:\n");
        for t in failed {
            print!("sig=`{}`, pub_key=`{}`\n", t.0, t.1);
        }

        passed
    }

    fn download_test() -> String {
        let client = Client::new();

        let mut res = client.get("https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data/script_valid.json")
            .header(Connection::close())
            .send().unwrap();

        let mut body = String::new();
        res.read_to_string(&mut body).unwrap();

        body
    }

    fn get_array(json: Json) -> Vec<Json> {
        match json {
            Json::Array(x) => x,
            _ => unreachable!(),
        }
    }

    fn get_string(json: Json) -> String {
        match json {
            Json::String(x) => x,
            _ => unreachable!(),
        }
    }
}
