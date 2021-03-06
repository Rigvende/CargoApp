package by.itechart.cargo.model;

import by.itechart.cargo.model.enumeration.EnumTypePostgreSql;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.*;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDate;
import java.util.List;
import java.util.Set;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@Builder
@Table(name = "user", schema = "public")
@TypeDef(
        name = "user_status",
        typeClass = EnumTypePostgreSql.class
)
public class User extends BaseEntity implements Serializable, Cloneable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_user", nullable = false, updatable = false)
    private Long id;

    @Column(name = "email", unique = true, nullable = false)
    private String email;

    @Column(name = "password", nullable = false)
    @JsonIgnore
    private String password;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "surname", nullable = false)
    private String surname;

    @Column(name = "patronymic", nullable = false)
    private String patronymic;

    @Column(name = "birthday", nullable = false)
    private LocalDate birthday;

    @Column(name = "photo")
    private String photo;

    @Embedded
    private Address address;

    @Column(name = "phone", nullable = false)
    private String phone;

    @Column(name = "passport")
    private String passport;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    @Type(type = "user_status")
    private Status status;

    @Column(name = "online")
    private boolean isOnline;

    @ManyToOne(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinColumn(name = "id_client_company", nullable = false)
    @JsonIgnore
    private ClientCompany clientCompany;

    @JsonManagedReference(value = "user_role")
    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.ALL})
    @JoinTable(
            name = "user_role",
            joinColumns = {@JoinColumn(name = "id_user")},
            inverseJoinColumns = {@JoinColumn(name = "id_role")}
    )
    private Set<Role> roles;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "registrationUser")
    @JsonBackReference(value = "reg_invoice")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private List<Invoice> registrationInvoice;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "checkingUser")
    @JsonBackReference(value = "check_invoice")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private List<Invoice> checkingInvoice;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "driver")
    @JsonBackReference(value = "driver_invoice")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private List<Invoice> driver;

    public enum Status {
        ACTIVE,
        BLOCKED,
        DELETED
    }

}
