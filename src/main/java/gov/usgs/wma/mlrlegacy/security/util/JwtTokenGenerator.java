package gov.usgs.wma.mlrlegacy.security.util;

import gov.usgs.wma.mlrlegacy.security.transfer.JwtUserDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;

/**
 * convenience class to generate a token for testing your requests.
 * Make sure the used secret here matches the on in your application.yml
 *
 * @author pascal alma
 */
public class JwtTokenGenerator {

    /**
     * Generates a JWT token containing username as subject, and userId and role as additional claims. These properties are taken from the specified
     * User object. Tokens validity is infinite.
     *
     * @param u the user for which the token will be generated
     * @return the JWT token
     */
    public static String generateToken(JwtUserDto u, String secret) {
        Claims claims = Jwts.claims().setSubject(u.getUsername());
        claims.put("userId", u.getId() + "");
        claims.put("role", u.getRole());

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, TextCodec.BASE64.decode(secret))
                .compact();
    }

    public static String SECRET = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl36tMz4Ft7dQ3uK+2GqXds2HkqNplUaO1jqPq74wZ1Qkme0CECQpWN84bpVLbIlWoHufR01Ylig9ctgOwV2zOfCQ/s6sX3jgZd/cLPMTrzNfX0Wf+sX1LIhP+lTXhCHp6eZN9lFSiaOyPlT/lCjYGKujSRguSflfEIVMZUAMgBzhdJntBFK/9owjyHHIe1ZFJfsTak1XA1PGcdz7AvlYKhv+QCWn1ynvrJ5eXvqWEr/Z6S9tI7V1zSCphV3B8tZgsnv0+Y6S1QmS3r2Phum8B5dh0O2naxS6f7rFN6r1NUKQ0YktDIAbUPV2Fm3h8Yf3DqrtZRc9jMFVO3zcEhnfsQIDAQAB";

    /**
     * @param args
     */
    public static void main(String[] args) {

        JwtUserDto user = new JwtUserDto();
        user.setId(123L);
        user.setUsername("Pascal");
        user.setRole("admin");

        System.out.println("**************************************\n\n" + generateToken(user, SECRET) + "\n\n**************************************");
    }

}
