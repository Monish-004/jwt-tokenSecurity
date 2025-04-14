package com.example.Spring.security.serviceImplementation;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static javax.crypto.Cipher.SECRET_KEY;

@Service
public class JwtService
{
    // For Our Understanding, Don't use in real time project [Manually Hardcoded our secretKey, but it is wrong way]

    private  String SECRET_KEY = "L2Z4cDgyNzByMWN4dzNhc3U3bGJmbmQ2Z3QxZ3JxM3ByNXFqZGFtc2FncGg=";


    private String secretKey;

    public JwtService()
    {
        secretKey = generateSecretKey();
    }


    // Generating a SecretKey, this is a correct Way. Use in Real-Time project also.
    public String generateSecretKey()
    {
        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance( "HmacSHA256"); // It Says Generate a key for this Algorithm
            SecretKey secretKey = keyGen.generateKey(); // Generating a key and storing into secretKey
            System.out.println("Hi");
            System.out.println("Secret Key : " + secretKey.toString());
            return Base64.getEncoder().encodeToString(secretKey.getEncoded()); // We are Encoding that secretKey
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("Error generating secret key", e);
        }
    }

    public String generateToken (String username) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims (claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration (new Date(System.currentTimeMillis() + 1000*60*3))
                //.and()
                .signWith(getKey(), SignatureAlgorithm. HS256).compact();
    }


    // For this Key[Inbuilt class], byte type should be return.
    private Key getKey()
    {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey); // We are decoding our secret key.
        System.out.println("Key is Decoded");
        System.out.println(Keys.hmacShaKeyFor(keyBytes));
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token)
    {
        // Extracting a username from Jwt Token
        return extractClaim(token, Claims::getSubject);
    }


    private <T> T extractClaim(String token, Function<Claims, T> claimResolver)
    {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token)
    {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build().parseClaimsJws(token).getBody();
    }

    public boolean validateToken(String token, UserDetails userDetails)
    {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token)
    {
        return extractExpiration (token). before (new Date());
    }
    private Date extractExpiration (String token)
    {
        return extractClaim(token, Claims::getExpiration);
    }
}
