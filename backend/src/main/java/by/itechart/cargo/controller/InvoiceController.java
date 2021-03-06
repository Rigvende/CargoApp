package by.itechart.cargo.controller;

import by.itechart.cargo.dto.model_dto.invoice.*;
import by.itechart.cargo.exception.AlreadyExistException;
import by.itechart.cargo.exception.NotFoundException;
import by.itechart.cargo.service.InvoiceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

import static by.itechart.cargo.security.RoleConstant.*;

@RestController
@RequestMapping("/v1/api/invoices")
@Validated
public class InvoiceController {
    private final InvoiceService invoiceService;
    private final NotificationController notificationController;

    @Autowired
    public InvoiceController(InvoiceService invoiceService, NotificationController notificationController) {
        this.invoiceService = invoiceService;
        this.notificationController = notificationController;
    }

    @GetMapping
    @Secured({OWNER, MANAGER, DRIVER, DISPATCHER})
    public ResponseEntity<InvoicePaginationResponse> findAll(@RequestParam int requestedPage, @RequestParam int invoicesPerPage) {
        return ResponseEntity.ok(invoiceService.findAll(requestedPage, invoicesPerPage));
    }

    @GetMapping("/initial/data")
    @Secured({OWNER, MANAGER, DRIVER, DISPATCHER})
    public ResponseEntity<DataForInvoiceCreating> findDataForInvoiceCreating() {
        return ResponseEntity.ok(invoiceService.findDataForInvoiceCreating());
    }

    @GetMapping("/driver")
    @Secured({DRIVER})
    public ResponseEntity<InvoicePaginationResponse> findInvoicesForDriver(@RequestParam(required = false) String number,
                                                                           @RequestParam int requestedPage,
                                                                           @RequestParam int invoicesPerPage) {
        if (number == null) {
            return ResponseEntity.ok(invoiceService.findAllForDriver(requestedPage, invoicesPerPage));
        } else {
            return ResponseEntity.ok(invoiceService.findAllByNumberStartsWithForDriver(number, requestedPage, invoicesPerPage));
        }
    }

    @GetMapping("/manager")
    @Secured({MANAGER})
    public ResponseEntity<InvoicePaginationResponse> findInvoicesForManager(@RequestParam(required = false) String number,
                                                                            @RequestParam int requestedPage,
                                                                            @RequestParam int invoicesPerPage) {
        if (number == null) {
            return ResponseEntity.ok(invoiceService.findAllForManager(requestedPage, invoicesPerPage));
        } else {
            return ResponseEntity.ok(invoiceService.findAllByNumberStartsWithForManager(number, requestedPage, invoicesPerPage));
        }
    }

    @GetMapping("/dispatcher")
    @Secured({DISPATCHER})
    public ResponseEntity<InvoicePaginationResponse> findInvoicesForDispatcher(@RequestParam(required = false) String number,
                                                                               @RequestParam int requestedPage,
                                                                               @RequestParam int invoicesPerPage) {
        if (number == null) {
            return ResponseEntity.ok(invoiceService.findAllForDispatcher(requestedPage, invoicesPerPage));
        } else {
            return ResponseEntity.ok(invoiceService.findAllByNumberStartsWithForDispatcher(number, requestedPage, invoicesPerPage));
        }
    }

    @GetMapping("/calendar")
    @Secured({MANAGER})
    public ResponseEntity<List<InvoiceResponse>> findInfoForCalendar() {
        return ResponseEntity.ok(invoiceService.findAllForCalendar());
    }

    @GetMapping("/{id}")
    @Secured({OWNER, MANAGER, DRIVER, DISPATCHER})
    public ResponseEntity<InvoiceResponse> findById(@PathVariable long id) throws NotFoundException {
        InvoiceResponse byId = invoiceService.findById(id);
        return ResponseEntity.ok(byId);
    }

    @PostMapping
    @Secured({OWNER, MANAGER, DRIVER, DISPATCHER})
    public ResponseEntity<String> save(@RequestBody @Valid InvoiceRequest invoiceRequest) throws AlreadyExistException, NotFoundException {
        Long id = invoiceService.save(invoiceRequest);
        notificationController.notifyAboutNewInvoice(id, invoiceRequest.getManagerId());
        return ResponseEntity.ok("Invoice has been saved");
    }

    @PostMapping("/status")
    @Secured({OWNER, MANAGER, DRIVER, DISPATCHER})
    public ResponseEntity<String> updateStatus(@RequestBody @Valid UpdateInvoiceStatusRequest invoiceRequest) throws NotFoundException {
        invoiceService.updateStatus(invoiceRequest);
        notificationController.notifyAboutInvoiceStatusChange(invoiceRequest.getId(), invoiceRequest.getStatus());
        return ResponseEntity.ok("Invoice status has been updated");
    }

    @PutMapping
    @Secured({OWNER, MANAGER, DRIVER, DISPATCHER})
    public ResponseEntity<String> update(@RequestBody @Valid InvoiceRequest invoiceRequest) throws NotFoundException, AlreadyExistException {
        invoiceService.updateInvoice(invoiceRequest);
        notificationController.notifyAboutInvoiceUpdate(invoiceRequest.getId());
        return ResponseEntity.ok("Invoice status has been updated");
    }
}
