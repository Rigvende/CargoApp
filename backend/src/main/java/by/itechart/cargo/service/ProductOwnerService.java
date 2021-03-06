package by.itechart.cargo.service;

import by.itechart.cargo.dto.model_dto.product_owner.ProductOwnerSaveRequest;
import by.itechart.cargo.dto.model_dto.product_owner.ProductOwnerPaginationResponse;
import by.itechart.cargo.dto.model_dto.product_owner.ProductOwnerUpdateRequest;
import by.itechart.cargo.exception.AlreadyExistException;
import by.itechart.cargo.exception.NotFoundException;
import by.itechart.cargo.model.ProductOwner;

public interface ProductOwnerService {

    ProductOwnerPaginationResponse findWithPagination(int requestedPage, int productOwnersPerPage);

    ProductOwnerPaginationResponse findByName(String name, int requestedPage, int productOwnersPerPage);

    ProductOwner findById(Long id) throws NotFoundException;

    void save(ProductOwnerSaveRequest productOwner) throws AlreadyExistException, NotFoundException;

    void update(ProductOwnerUpdateRequest productOwnerUpdateRequest) throws NotFoundException, AlreadyExistException;

    void delete(Long id) throws NotFoundException;
}
