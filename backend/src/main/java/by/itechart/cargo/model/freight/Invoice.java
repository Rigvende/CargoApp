package by.itechart.cargo.model.freight;

import by.itechart.cargo.model.ClientCompany;
import by.itechart.cargo.model.User;
import by.itechart.cargo.model.enumeration.EnumTypePostgreSql;
import by.itechart.cargo.model.enumeration.InvoiceStatus;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDate;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "invoice")
@TypeDef(
        name = "invoice_status",
        typeClass = EnumTypePostgreSql.class
)
public class Invoice implements Serializable, Cloneable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_invoice")
    private Long id;

    @Column(name = "number", nullable = false)
    private String number;

    @Enumerated(EnumType.STRING)
    @Type(type = "invoice_status")
    @Column(name = "status")
    private InvoiceStatus invoiceStatus;

    @Column(name = "registration_date", nullable = false)
    private LocalDate registrationDate;

    @Column(name = "checking_date")
    private LocalDate checkingDate;

    @Column(name = "close_date")
    private LocalDate closeDate;

    @Column(name = "shipper", nullable = false)
    private String shipper;

    @Column(name = "consignee", nullable = false)
    private String consignee;

    @JoinColumn(name = "id_driver", nullable = false)
    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JsonManagedReference
    private Driver driver;

    @JoinColumn(name = "id_user_registration", nullable = false)
    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JsonManagedReference(value = "reg_invoice")
    private User registrationUser;

    @JoinColumn(name = "id_user_checking")
    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JsonManagedReference(value = "check_invoice")
    private User checkingUser;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "invoice")
    private List<Product> products;

    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "id_client_company", nullable = false)
    @JsonBackReference(value = "invoice_company")
    private ClientCompany clientCompany;

}