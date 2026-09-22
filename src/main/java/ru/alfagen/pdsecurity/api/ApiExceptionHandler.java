package ru.alfagen.pdsecurity.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import ru.alfagen.pdsecurity.service.CapacityException;
import ru.alfagen.pdsecurity.service.ConflictException;
import ru.alfagen.pdsecurity.service.ExpiredException;
import ru.alfagen.pdsecurity.service.ForbiddenException;

/**
 * Maps exceptions to safe error responses. The body never echoes the payload.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ApiError> conflict() {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ApiError("conflict", "payload_id already active"));
    }

    @ExceptionHandler(ExpiredException.class)
    public ResponseEntity<ApiError> expired() {
        return ResponseEntity.status(HttpStatus.GONE).body(new ApiError("expired", "session expired"));
    }

    @ExceptionHandler(CapacityException.class)
    public ResponseEntity<ApiError> capacity() {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", "1")
                .body(new ApiError("capacity", "no capacity"));
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<ApiError> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiError("forbidden", "restoration disabled"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validation() {
        return ResponseEntity.badRequest().body(new ApiError("invalid", "invalid request"));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> unreadable() {
        return ResponseEntity.badRequest().body(new ApiError("invalid", "malformed json"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> generic() {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError("internal", "internal error"));
    }
}