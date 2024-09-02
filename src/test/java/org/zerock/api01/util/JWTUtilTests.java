package org.zerock.api01.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

@SpringBootTest
@Log4j2
public class JWTUtilTests {

    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void generate() {
        Map<String, Object> claimMap = Map.of("mid", "ABCDE");
        String jwtStr = jwtUtil.generateToken(claimMap, 1);
        log.info(jwtStr);
    }

    @Test
    public void validate() {
        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MjUyNDU5MDYsIm1pZCI6IkFCQ0RFIiwiaWF0IjoxNzI1MjQ1ODQ2fQ.jDzCCytx0nppi5Fne9KBV66aJxIL9DiL1VRCqkLmDpQ";

        Map<String, Object> claim = jwtUtil.validatedToken(jwtStr);
        log.info(claim);
    }

/*
유효기간이 지난 토큰
io.jsonwebtoken.ExpiredJwtException: JWT expired at 2024-09-02T11:58:26Z. Current time: 2024-09-02T12:02:34Z, a difference of 248672 milliseconds.  Allowed clock skew: 0 milliseconds.
 */

    @Test
    public void all() {
        String jwtStr = jwtUtil.generateToken(Map.of("mid", "AAAA", "email", "aaaa@bbb.com"), 1);
        log.info(jwtStr);
        Map<String, Object> claim = jwtUtil.validatedToken(jwtStr);
        log.info("MID="+claim.get("mid"));
        log.info("EMAIL={}", claim.get("email"));
    }
}
