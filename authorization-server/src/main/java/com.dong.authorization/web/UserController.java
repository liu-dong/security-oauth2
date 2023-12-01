package com.dong.authorization.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 用户信息
 *
 * @author LD 2023/10/27
 */
@RestController
@RequestMapping("/user")
public class UserController {


    /**
     * 获取用户信息
     *
     * @return
     */
    @GetMapping("/getUserDetail")
    public String getUserDetail() {

        return "LD";
    }


}
