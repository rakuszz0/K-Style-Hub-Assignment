package bcrypt

import (
	"log"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func HashingPassword(password string) (string, error) {
	// Ensure password is properly trimmed
	password = strings.TrimSpace(password)
	hashedByte, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedByte), nil
}

func CheckPasswordHash(password, hash string) bool {
	password = strings.TrimSpace(password)
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		log.Printf("BCrypt Error: %v", err)
		log.Printf("Password: %q", password)
		log.Printf("Hash: %q", hash)
		return false
	}
	return true
}
