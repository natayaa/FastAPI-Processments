from typing import Optional, Any
from typing import AnyStr, Literal
from pydantic import BaseModel, Field, EmailStr, field_validator, model_validator

import re


class BaseResponse(BaseModel):
    status: int = Field(200, ge=100, le=599, description="HTTP status code")
    message: AnyStr = ""
    data: Any = None

# User Registration
class RegisterUser(BaseModel):
    username: AnyStr = Field(..., min_length=3, max_length=50)
    password: AnyStr = Field(..., min_length=7)
    confirm_password: AnyStr = Field(..., min_length=7)
    email: EmailStr
    security_pin: int = Field(..., ge=000000, le=999999, description="4-digit PIN code")
    default_role: Literal["Guest", "User", "Admin"] = "Guest"

    @field_validator("password")
    def validate_password(cls, value: str) -> str:
        if len(value) <= 6:
            raise ValueError("Password must be longer than 6 characters")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must include at least one uppercase letter")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise ValueError("Password must include at least one special character")
        if len(re.findall(r"\d", value)) < 2:
            raise ValueError("Password must include at least two digits")
        return value

    @model_validator(mode="after")
    def check_passwords_match(self) -> "RegisterUser":
        if self.password != self.confirm_password:
            raise ValueError("Password and confirm_password do not match")
        return self


class UserDetails(RegisterUser):
    first_name: AnyStr = Field(..., min_length=2)
    middle_name: Optional[AnyStr] = ""
    last_name: AnyStr = Field(..., min_length=2)

# End of Register User