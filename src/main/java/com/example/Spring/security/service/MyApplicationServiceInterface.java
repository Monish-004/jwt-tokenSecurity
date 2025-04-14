package com.example.Spring.security.service;

import com.example.Spring.security.entity.MyApplication;

public interface MyApplicationServiceInterface
{
    MyApplication saveRegisterationDetails(MyApplication newUserForRegisteration);
}
