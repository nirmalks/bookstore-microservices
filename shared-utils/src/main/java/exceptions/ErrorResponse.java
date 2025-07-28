package exceptions;

import java.util.List;

public class ErrorResponse {
    private String message;
    private int status;
    private List<String> errors;

    public ErrorResponse(String message, int statusCode, List<String> errors) {
        this.message = message;
        this.status = statusCode;
        this.errors = errors;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }
}