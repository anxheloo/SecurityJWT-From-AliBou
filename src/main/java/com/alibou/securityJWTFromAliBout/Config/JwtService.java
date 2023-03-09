package com.alibou.securityJWTFromAliBout.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    //We generated this from https://www.allkeysgenerator.com/ 256-bit, Hex? Yes
    private static final String SECRET_KEY = "58703273357638792F423F4428472B4B6250655368566D597133743677397A24";


    public String extractUsername(String jwt) {
        System.out.println(extractClaim(jwt, Claims::getSubject));  //Check the return output of this method
        return extractClaim(jwt, Claims::getSubject);
    }


    public <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver){

        final Claims claims = extractAllClaims(jwt);
        System.out.println(claims);     //Check the output of claims
        System.out.println(claimsResolver.apply(claims));  //Check the return output of the method
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){

        //Check the return output of the method
        System.out.println(generateToken(new HashMap<>(), userDetails));
        return generateToken(new HashMap<>(), userDetails);
    }


    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){

        //Check the return output of the method
        System.out.println(Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact());

        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims extractAllClaims(String jwt) {

        //Check the output of the method
//        System.out.println(Jwts
//                .parserBuilder()
//                .setSigningKey(getSignInKey())
//                .build()
//                .parseClaimsJwt(jwt)
//                .getBody());

        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        System.out.println(keyBytes);   //Check the output of keyBytes
        System.out.println(Keys.hmacShaKeyFor(keyBytes));  //Check the output of Keys.hmacShaKeyFor(keyBytes)
        return Keys.hmacShaKeyFor(keyBytes);
    }




    public boolean isTokenValid(String jwt, UserDetails userDetails){

        final String username = extractUsername(jwt);
        System.out.println("We print the username token: " + username); //We print the username token just to check for ourself , and below we check if it is valid or no
        System.out.println((username.equals(userDetails.getUsername())) && !isTokenExpired(jwt)); // We print True or False
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(jwt);
    }

    private boolean isTokenExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }

    private Date extractExpiration(String jwt) {
        return extractClaim(jwt, Claims::getExpiration);
    }


}
