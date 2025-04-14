package com.example.Spring.security.repository;

import com.example.Spring.security.entity.MyApplication;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MyApplicationRepository extends JpaRepository<MyApplication,Integer>
{
    MyApplication findByUsername(String username);

}
