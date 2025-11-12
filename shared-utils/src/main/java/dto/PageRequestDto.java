package dto;

public class PageRequestDto {

	private int page = 0;

	private int size = 10;

	private String sortKey = "id";

	private String sortOrder = "asc";

	public PageRequestDto() {
	}

	public PageRequestDto(int page, int size, String sortKey, String sortOrder) {
		this.page = page;
		this.size = size;
		this.sortKey = sortKey;
		this.sortOrder = sortOrder;
	}

	public int getPage() {
		return page;
	}

	public void setPage(int page) {
		this.page = page;
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public String getSortKey() {
		return sortKey;
	}

	public void setSortKey(String sortKey) {
		this.sortKey = sortKey;
	}

	public String getSortOrder() {
		return sortOrder;
	}

	public void setSortOrder(String sortOrder) {
		this.sortOrder = sortOrder;
	}

	@Override
	public String toString() {
		return "dto.PageRequestDto{" + "page=" + page + ", size=" + size + ", sortKey='" + sortKey + '\''
				+ ", sortOrder='" + sortOrder + '\'' + '}';
	}

}
