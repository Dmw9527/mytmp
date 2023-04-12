package com.example.dynamicpermission.service;

import com.example.dynamicpermission.entity.Menu;
import com.example.dynamicpermission.mapper.MenuMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MenuService {
    @Autowired
    MenuMapper menuMapper;

    @Cacheable(cacheNames = "cache-component1")
    public List<Menu> getAllMenus() {
        System.out.println(111111);//验证连接了一次数据库还是两次
        return menuMapper.getAllMenus();
    }

}
