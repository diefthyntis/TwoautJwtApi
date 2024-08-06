package com.diefthyntis.TwoautJwtApi.auth;

public class ReturnedResponse {
  private String message;

  public ReturnedResponse(String message) {
    this.message = message;
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }
}