package org.wso2.carbon.identity.user.store.ws.model;

import java.io.Serializable;

public class ResultDTO implements Serializable{

    private boolean success;
    private String message;

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
