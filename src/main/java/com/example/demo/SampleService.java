package com.example.demo;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController

public class SampleService {

	@RequestMapping(path = "mysecret", method = RequestMethod.GET)
	public String getSecrets() {

		return "I know microservices";
	}
}
