package com.example.Spring.security.serviceImplementation;

import com.example.Spring.security.entity.MyApplication;
import com.example.Spring.security.repository.MyApplicationRepository;
import com.example.Spring.security.service.MyApplicationServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class MyApplicationServiceLayer implements MyApplicationServiceInterface,UserDetailsService
{
    @Autowired
    private MyApplicationRepository myApplicationRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        MyApplication dbUsername = myApplicationRepository.findByUsername(username);
        if(dbUsername == null)
        {
            System.out.println("User not found 404!!");
            throw new UsernameNotFoundException("User Not Found");
        }
        return dbUsername;
    }

    @Override
    public MyApplication saveRegisterationDetails(MyApplication newUserForRegisteration)
    {
        System.out.println(newUserForRegisteration.getUsername());
        System.out.println(newUserForRegisteration.getPassword());
        newUserForRegisteration.setPassword(passwordEncoder.encode(newUserForRegisteration.getPassword()));
        return myApplicationRepository.save(newUserForRegisteration);
    }
}



