package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.annotations.ApiModelProperty;

public class EditEndEntityRequest {
  @ApiModelProperty(value = "username",required = true  )
  private String username;
  @ApiModelProperty(value = "email",required = true  )
  private String email;

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }
}
