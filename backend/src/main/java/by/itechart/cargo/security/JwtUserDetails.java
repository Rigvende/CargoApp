package by.itechart.cargo.security;

import by.itechart.cargo.model.Address;
import by.itechart.cargo.model.ClientCompany;
import by.itechart.cargo.model.Role;
import by.itechart.cargo.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Set;

@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtUserDetails implements UserDetails {

    private long id;
    private String email;
    private String password;
    private String name;
    private String surname;
    private String patronymic;
    private LocalDate birthday;
    private Address address;
    private String passport;
    private User.Status status;
    private ClientCompany clientCompany;
    private String phone;
    private String photo;
    private Set<Role> roles;
    private Collection<? extends GrantedAuthority> authorities;
    private boolean isEnable;

    public User toUser() {
        return User.builder()
                .id(id)
                .email(email)
                .password(password)
                .name(name)
                .surname(surname)
                .patronymic(patronymic)
                .birthday(birthday)
                .address(address)
                .passport(passport)
                .status(status)
                .clientCompany(clientCompany)
                .roles(roles)
                .photo(photo)
                .phone(phone)
                .build();
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return isEnable;
    }

}
