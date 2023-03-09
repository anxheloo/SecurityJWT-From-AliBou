package com.alibou.securityJWTFromAliBout.user;

import com.alibou.securityJWTFromAliBout.Token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder //help us build our object in an easy way
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="_user", uniqueConstraints = @UniqueConstraint(columnNames = "email")) //We cannot create an table named "User" cuz it exist in hibernate properties so we make it called " user"
public class User implements UserDetails {

    @Id
    //@GeneratedValue  //default value is (strategy = GenerationType.AUTO)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToMany(mappedBy = "user")
    private List<Token>tokens;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    //This is a method of userdetails class, but lombok also have this method. I changed the property name from 'password' to 'pass',
    //than implement the method getPassword() from userDetails, than set the property back again to password
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
