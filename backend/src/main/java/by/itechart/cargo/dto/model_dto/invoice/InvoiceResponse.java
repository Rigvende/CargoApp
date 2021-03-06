package by.itechart.cargo.dto.model_dto.invoice;

import by.itechart.cargo.dto.model_dto.product_owner.ProductOwnerInvoiceResponse;
import by.itechart.cargo.model.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class InvoiceResponse {

    private Long id;
    private ProductOwnerInvoiceResponse productOwnerDTO;
    private String number;
    private Invoice.Status status;
    private LocalDate registrationDate;
    private LocalDate checkingDate;
    private LocalDate closeDate;
    private Storage shipper;
    private Storage consignee;
    private User driver;
    private User registrationUser;
    private User checkingUser;
    private List<Product> products;
    private Waybill waybill;
    private Act act;
    private String comment;

    public static InvoiceResponse toInvoiceResponse(Invoice invoice) {
        InvoiceResponse response = new InvoiceResponse();
        response.setId(invoice.getId());
        response.setStatus(invoice.getStatus());
        response.setNumber(invoice.getNumber());
        response.setRegistrationDate(invoice.getRegistrationDate());
        response.setCheckingDate(invoice.getCheckingDate());
        response.setCloseDate(invoice.getCloseDate());
        response.setDriver(invoice.getDriver());
        response.setComment(invoice.getComment());
        response.setShipper(invoice.getShipper());
        response.setConsignee(invoice.getConsignee());
        response.setRegistrationUser(invoice.getRegistrationUser());
        response.setCheckingUser(invoice.getCheckingUser());
        response.setProducts(invoice.getProducts());
        response.setProductOwnerDTO(ProductOwnerInvoiceResponse.fromProductOwner(invoice.getProductOwner()));
        response.setWaybill(invoice.getWaybill());
        response.setAct(invoice.getAct());
        return response;
    }

    public static List<InvoiceResponse> fromInvoices(List<Invoice> invoices) {
        List<InvoiceResponse> invoiceResponses = new ArrayList<>();
        for (Invoice invoice : invoices) {
            invoiceResponses.add(toInvoiceResponse(invoice));
        }
        return invoiceResponses;
    }

}
