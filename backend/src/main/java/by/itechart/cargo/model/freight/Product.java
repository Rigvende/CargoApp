package by.itechart.cargo.model.freight;

import by.itechart.cargo.model.enumeration.Status;
import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "product")
public class Product implements Serializable, Cloneable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, updatable = false)
    private Long id;

    @Column(name = "name", nullable = false)
    @NotBlank
    private String name;

    @Column(name = "quantity", nullable = false)
    @NotNull
    private Integer quantity;

    @Column(name = "measure", nullable = false)
    @NotBlank
    private String measure;

    @Column(name = "price", nullable = false)
    @NotNull
    private Long price;

    @Column(name = "sum", nullable = false)
    @NotNull
    private Long sum;

    @Column(name = "mass", nullable = false)
    @NotBlank
    private String mass;

    @Column(name = "status", nullable = false)
    @NotNull
    private Status productStatus;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "id_delivery_note")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private DeliveryNote deliveryNote;


}
