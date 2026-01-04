package org.example.microservice.apigateway.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.*;

public class HeaderMutableHttpServletRequest extends HttpServletRequestWrapper {
    private final Map<String, String> customHeaders = new HashMap<>();

    public HeaderMutableHttpServletRequest(HttpServletRequest request) {
        super(request);
    }

    public void putHeader(String name, String value) {
        customHeaders.put(name, value);
    }

    @Override
    public String getHeader(String name) {
        String headerValue = customHeaders.get(name);
        if (headerValue != null) {
            return headerValue;
        }
        return ((HttpServletRequest) getRequest()).getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        Set<String> names = new HashSet<>(customHeaders.keySet());
        Enumeration<String> original = ((HttpServletRequest) getRequest()).getHeaderNames();
        while (original.hasMoreElements()) {
            names.add(original.nextElement());
        }
        return Collections.enumeration(names);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        String headerValue = customHeaders.get(name);
        if (headerValue != null) {
            List<String> values = new ArrayList<>();
            values.add(headerValue);
            return Collections.enumeration(values);
        }
        return ((HttpServletRequest) getRequest()).getHeaders(name);
    }
}

