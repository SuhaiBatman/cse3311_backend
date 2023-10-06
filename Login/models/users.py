from ast import Dict
from bson import ObjectId
from typing import Any, Optional
from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel): ##basic info we will need from user
    username: str
    email: EmailStr
    password: str
    pnumber: str
    fName: str
    lName: str
    address: str
    uType: Optional[str] = 'user'
    
    @staticmethod
    def validate_obj(obj: 'UserCreate', **kwargs) -> bool: ##validate if it is an object
        if not obj:
            return False
        
        obj_encoded: Dict[str, Any] = obj.dict()
        
        for key in obj_encoded.keys():
            if not obj_encoded[key]:
                return False
            
        return True