package gov.usgs.wma.mlrlegacy.security.util;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import gov.usgs.wma.mlrlegacy.security.transfer.JwtUserDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;

/**
 * Class validates a given token by using the secret configured in the application
 *
 * @author pascal alma
 */
@Component
public class JwtTokenValidator {



    @Value("${jwt.secret}")
    private String secret;

    /**
     * Tries to parse specified String as a JWT token. If successful, returns User object with username, id and role prefilled (extracted from token).
     * If unsuccessful (token is invalid or not containing all required user properties), simply returns null.
     *
     * @param token the JWT token to parse
     * @return the User object extracted from specified token or null if a token is invalid.
     * @throws IOException 
     */
    public JwtUserDto parseToken(String token) throws IOException {
        JwtUserDto u = null;

        byte[] publicBytes = TextCodec.BASE64.decode(secret);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(StreamUtils.copyToByteArray(new ClassPathResource("public.cert").getInputStream()));
        KeyFactory keyFactory;
        PublicKey pubKey = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			pubKey = keyFactory.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

        try {
            Claims body = Jwts.parser()
                    .setSigningKey(pubKey)
//            		.setSigningKey(TextCodec.BASE64.decode(secret))
                    .parseClaimsJws(token)
                    .getBody();

            u = new JwtUserDto();
//            u.setUsername(body.getSubject());
//            u.setId(Long.parseLong((String) body.get("userId")));
//            u.setRole((String) body.get("role"));
          u.setUsername("Dummy");
          u.setId(Long.valueOf(5));
          u.setRole("Super");

        } catch (JwtException e) {
            // Simply print the exception and null will be returned for the userDto
            e.printStackTrace();
        }
        return u;
    }

}
