package org.wso2.mcpgov.idjag;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The mediator's request handling that does not need a live Synapse message context. The full
 * mediator is exercised on the APIM gateway itself (next step of the plan).
 */
class IdJagTokenMediatorTest {

    @Test
    void bearerPrefixIsToleratedInAnyCase() {
        assertEquals("a.b.c", IdJagTokenMediator.bearerFrom("Bearer a.b.c"));
        assertEquals("a.b.c", IdJagTokenMediator.bearerFrom("bearer   a.b.c "));
        assertEquals("a.b.c", IdJagTokenMediator.bearerFrom("a.b.c"));
    }

    @Test
    void emptyHeaderValuesMeanNoToken() {
        assertNull(IdJagTokenMediator.bearerFrom(null));
        assertNull(IdJagTokenMediator.bearerFrom("   "));
        assertNull(IdJagTokenMediator.bearerFrom("Bearer "));
    }

    @Test
    void onlyThreePartValuesLookLikeAJwt() {
        assertTrue(IdJagTokenMediator.looksLikeJwt("a.b.c"));
        assertFalse(IdJagTokenMediator.looksLikeJwt("opaque-token"));
        assertFalse(IdJagTokenMediator.looksLikeJwt("a.b"));
        assertFalse(IdJagTokenMediator.looksLikeJwt("a.b.c.d.e"));
    }

    @Test
    void jsonRpcIdsComeBackAsTheClientSentThem() {
        // APIM's McpRequest holds ids parsed by Gson as Object: numbers arrive as doubles.
        assertEquals("7", IdJagTokenMediator.jsonRpcId(7.0d).toString());
        assertEquals("7", IdJagTokenMediator.jsonRpcId(7L).toString());
        assertEquals("1.5", IdJagTokenMediator.jsonRpcId(1.5d).toString());
        assertEquals("\"req-1\"", IdJagTokenMediator.jsonRpcId("req-1").toString());
        assertEquals("null", IdJagTokenMediator.jsonRpcId(null).toString());
    }

    @Test
    void headerLookupAndRemovalIgnoreCase() {
        // Transport header maps are usually case-insensitive, but a plain map must work too, or
        // the client's gateway token could survive next to the upstream one.
        Map<String, Object> headers = new HashMap<>();
        headers.put("x-id-token", "Bearer a.b.c");
        headers.put("AUTHORIZATION", "Bearer gateway-token");

        assertEquals("Bearer a.b.c", IdJagTokenMediator.header(headers, "X-ID-Token"));
        IdJagTokenMediator.removeHeader(headers, "Authorization");
        IdJagTokenMediator.removeHeader(headers, "X-ID-Token");
        assertTrue(headers.isEmpty());
    }
}
