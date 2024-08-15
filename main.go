package main

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"net/http"
	"time"

	pb "golang-jwt-grpc/github.com/kmsdoit/golang-jwt-grpc" // gRPC 프로토콜을 컴파일한 패키지
)

var jwtSecretKey = []byte("jwttoken") // 비밀 키

type server struct {
	pb.UnimplementedAuthServiceServer
}

type LoginDto struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type CustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// 로그인 요청을 처리하고 JWT 토큰을 생성하여 반환하는 REST API 핸들러
func Login(c *gin.Context) {
	var loginDto LoginDto
	if err := c.BindJSON(&loginDto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//// 여기서 실제 사용자 인증 절차가 필요합니다 (예: 사용자 이름과 비밀번호 확인).
	//// 예제에서는 간단히 "user"와 "password"로 하드코딩된 검증을 수행합니다.
	//if loginDto.Username != "user" || loginDto.Password != "password" {
	//	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	//	return
	//}

	// JWT 토큰 생성
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &CustomClaims{
		Username: loginDto.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// gRPC 메서드로 토큰 검증을 처리하는 함수
func (s *server) VerifyToken(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	tokenString := req.Token
	claims := &CustomClaims{}
	log.Println("이 부분은 rpc영역 호출입니다")

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if err != nil || !token.Valid {
		return &pb.VerifyResponse{Valid: false, ErrorMessage: "Unauthorized"}, nil
	}

	return &pb.VerifyResponse{Valid: true, Username: claims.Username}, nil
}

func main() {
	// Gin을 사용하여 REST API 서버 실행
	go func() {
		r := gin.Default()
		r.POST("/login", Login)
		r.Run(":8080") // REST API 서버는 8080 포트에서 실행
	}()

	// gRPC 서버 설정
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterAuthServiceServer(s, &server{})

	// gRPC 클라이언트에서 Reflection을 통해 서비스 정보를 검색할 수 있도록 설정
	reflection.Register(s)

	log.Println("gRPC server listening on port 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
