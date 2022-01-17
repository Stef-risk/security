package com.stefan.security.configs;

import com.stefan.security.login.Md5PasswordEncoder;
import com.stefan.security.login.UserSecurity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserSecurity userSecurity;
    @Autowired
    private PersistentTokenRepository persistentTokenRepository;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Md5PasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //处理登录请求
        http.formLogin()
                .loginPage("/toLogin")
                .usernameParameter("name")
                .passwordParameter("pswd")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/toMain")
                .failureUrl("/toLogin");

        //访问控制
        http.authorizeRequests()
                .antMatchers("/toLogin","/register","/login","/favicon.ico").permitAll()
                .antMatchers("/**/*.js").permitAll()
                .regexMatchers(".*[.]css").permitAll()
                .anyRequest().authenticated();

        http.logout()
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .logoutSuccessUrl("/")
                .logoutUrl("/logout");

        //关闭CSRF安全协议
        http.csrf().disable();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        return new JdbcTokenRepositoryImpl();
    }
}
