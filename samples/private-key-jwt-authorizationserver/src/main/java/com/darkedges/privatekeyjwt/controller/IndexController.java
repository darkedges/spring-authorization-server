package com.darkedges.privatekeyjwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
	@GetMapping(value = "/resources", produces = "application/json")
	public String getResources() {
		System.out.println("/resources");
		String keys = "{\"keys\":[{"
				+ "\"kty\": \"EC\","
				+ "\"d\": \"5rjI4pBE_C2RbQ0W0iVuPk79cqZ-2SazUnLo5bndl7Y\","
				+ "\"use\": \"sig\","
				+ "\"crv\": \"P-256\","
				+ "\"kid\": \"cUExntQN1qVJB7SVVQdO6B0U21hMM0203lVmfjAU2to\","
				+ "\"x\": \"XMCi6Cc-v-Hw_dVKgfimfllfsdCqRGTeDzHiGBcpEKU\","
				+ "\"y\": \"lmMC8AS0FwEYMLHuCpTJ1zKwxNUeJfuH3Nl_faHa7qU\","
				+ "\"alg\": \"ES256\"}]}";
		return keys;
	}
}
