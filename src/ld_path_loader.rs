use std::collections::HashMap;
use std::fs;

pub struct LdPathLoader {
    paths: Vec<String>,
    libraries: HashMap<String, String>,
}

impl LdPathLoader {
    pub fn new(ld_library_path: &str) -> LdPathLoader {
        let separated_paths: Vec<&str> =
            ld_library_path.split(":").filter(|p| p.len() > 0).collect();
        LdPathLoader {
            paths: separated_paths.iter().map(|a| a.to_string()).collect(),
            libraries: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: &String) -> Option<String> {
        let mut result = Option::None;
        if let Some(value) = self.libraries.get(key) {
            result = Option::Some(value.clone());
        } else {
            for path in self.paths.iter() {
                let dir_paths = fs::read_dir(path)
                    .expect(format!("Unable to read directory {}", path).as_str());
                for dir_path in dir_paths {
                    let dir_file = dir_path.unwrap();
                    let absolute_path = fs::canonicalize(dir_file.path()).unwrap();
                    if let Some(abs_path) = absolute_path.to_str() {
                        self.libraries.insert(key.clone(), abs_path.to_string());
                        result = Option::Some(abs_path.to_string());
                    }
                }
            }
        }
        result
    }
}
