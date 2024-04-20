use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use rand_core::OsRng;
use uuid::Uuid;

use std::collections::HashMap;

pub trait Users {
    fn create_user(&mut self, username: String, password: String) -> Result<(), String>;
    fn get_user_uuid(&self, username: String, password: String) -> Option<String>;
    fn delete_user(&mut self, user_uuid: String);
}

#[derive(Clone)]
pub struct User {
    user_uuid: String,
    username: String,
    password: String,
}

#[derive(Default)]
pub struct UsersImpl {
    uuid_to_user: HashMap<String, User>,
    username_to_user: HashMap<String, User>,
}

impl Users for UsersImpl {
    fn create_user(&mut self, username: String, password: String) -> Result<(), String> {
        // TODO: Check if username already exist. If so return an error.
        match self.username_to_user.get(&username) {
            Some(name) => {
                return Err("Username {name} already exists".to_owned());
            }
            None => {
                let salt = SaltString::generate(&mut OsRng);

                let hashed_password = Pbkdf2
                    .hash_password(password.as_bytes(), &salt)
                    .map_err(|e| format!("Failed to hash password.\n{e:?}"))?
                    .to_string();
        
                let user: User = User{
                    user_uuid: Uuid::new_v4().to_string(),
                    username: username.clone(),
                    password: hashed_password,
                }; // Create new user with unique uuid and hashed password.
        
                self.username_to_user.insert(username, user.clone());
                self.uuid_to_user.insert(user.user_uuid.clone(), user);
        
                return Ok(());
            }
        }

    }

    fn get_user_uuid(&self, username: String, password: String) -> Option<String> {
        
        let user: Option<&User> = self.username_to_user.get(&username); // Retrieve `User` or return `None` is user can't be found.
        if user.is_none() {
            return None;
        }
        // Get user's password as `PasswordHash` instance. 
        let hashed_password = user.unwrap().password.clone();
        let parsed_hash = PasswordHash::new(&hashed_password).ok()?;

        // Verify passed in password matches user's password.
        let result = Pbkdf2.verify_password(password.as_bytes(), &parsed_hash);

        // TODO: If the username and password passed in matches the user's username and password return the user's uuid.

        match result {
            Ok(_) => return Some(user.unwrap().user_uuid.clone()),
            Err(_) => return None,
        }
 
    }

    fn delete_user(&mut self, user_uuid: String) {
        let username = self.uuid_to_user.remove(&user_uuid).unwrap().username;
        self.username_to_user.remove(&username).unwrap();
    
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_user() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert_eq!(user_service.uuid_to_user.len(), 1);
        assert_eq!(user_service.username_to_user.len(), 1);
    }

    #[test]
    fn should_fail_creating_user_with_existing_username() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let result = user_service.create_user("username".to_owned(), "password".to_owned());

        assert!(result.is_err());
    }

    #[test]
    fn should_retrieve_user_uuid() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert!(user_service
            .get_user_uuid("username".to_owned(), "password".to_owned())
            .is_some());
    }

    #[test]
    fn should_fail_to_retrieve_user_uuid_with_incorrect_password() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert!(user_service
            .get_user_uuid("username".to_owned(), "incorrect password".to_owned())
            .is_none());
    }

    #[test]
    fn should_delete_user() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let user_uuid = user_service
            .get_user_uuid("username".to_owned(), "password".to_owned())
            .unwrap();

        user_service.delete_user(user_uuid);

        assert_eq!(user_service.uuid_to_user.len(), 0);
        assert_eq!(user_service.username_to_user.len(), 0);
    }
}
