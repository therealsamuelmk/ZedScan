package com.microlasan.zedscan.ui.history;

import android.app.AlertDialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.navigation.fragment.NavHostFragment;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.microlasan.zedscan.R;
import com.microlasan.zedscan.data.SpamStore;
import com.microlasan.zedscan.data.db.SpamEventDao;
import com.microlasan.zedscan.data.db.SpamEventEntity;
import com.microlasan.zedscan.data.db.ZedScanDb;
import com.microlasan.zedscan.databinding.FragmentHistoryBinding;

public class HistoryFragment extends Fragment {

    private FragmentHistoryBinding binding;
    private SpamHistoryAdapter adapter;
    private SpamEventDao dao;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        binding = FragmentHistoryBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        dao = ZedScanDb.get(requireContext()).spamEventDao();

        adapter = new SpamHistoryAdapter();
        adapter.setListener(new SpamHistoryAdapter.Listener() {
            @Override
            public void onItemClicked(SpamEventEntity event) {
                openMap(event);
            }

            @Override
            public void onItemLongPressed(SpamEventEntity event) {
                confirmDeleteOne(event);
            }
        });

        binding.recyclerHistory.setLayoutManager(new LinearLayoutManager(requireContext()));
        binding.recyclerHistory.setAdapter(adapter);

        attachSwipeToDelete();

        dao.observeAll().observe(getViewLifecycleOwner(), adapter::submit);

        if (binding.btnClearHistory != null) {
            binding.btnClearHistory.setOnClickListener(v -> confirmClearAll());
        }
    }

    private void attachSwipeToDelete() {
        ItemTouchHelper.SimpleCallback callback = new ItemTouchHelper.SimpleCallback(
                0,
                ItemTouchHelper.LEFT | ItemTouchHelper.RIGHT
        ) {
            @Override
            public boolean onMove(@NonNull RecyclerView recyclerView,
                                  @NonNull RecyclerView.ViewHolder viewHolder,
                                  @NonNull RecyclerView.ViewHolder target) {
                return false;
            }

            @Override
            public void onSwiped(@NonNull RecyclerView.ViewHolder viewHolder, int direction) {
                int position = viewHolder.getBindingAdapterPosition();
                SpamEventEntity event = adapter.getItem(position);

                if (event == null) {
                    adapter.notifyItemChanged(position);
                    return;
                }

                confirmDeleteFromSwipe(event, position);
            }
        };

        new ItemTouchHelper(callback).attachToRecyclerView(binding.recyclerHistory);
    }

    private void confirmDeleteFromSwipe(SpamEventEntity event, int position) {
        if (getContext() == null) return;

        String sender = event.sender == null || event.sender.trim().isEmpty()
                ? "Unknown"
                : event.sender.trim();

        new AlertDialog.Builder(requireContext())
                .setTitle("Delete event?")
                .setMessage("Delete this spam event from history?\n\n" + sender)
                .setNegativeButton("Cancel", (dialog, which) -> {
                    dialog.dismiss();
                    adapter.notifyItemChanged(position);
                })
                .setPositiveButton("Delete", (dialog, which) ->
                        SpamStore.deleteById(requireContext(), event.id))
                .setOnCancelListener(dialog -> adapter.notifyItemChanged(position))
                .show();
    }

    private void confirmDeleteOne(SpamEventEntity event) {
        if (event == null || getContext() == null) return;

        String sender = event.sender == null || event.sender.trim().isEmpty()
                ? "Unknown"
                : event.sender.trim();

        new AlertDialog.Builder(requireContext())
                .setTitle("Delete event?")
                .setMessage("Delete this spam event from history?\n\n" + sender)
                .setNegativeButton("Cancel", (dialog, which) -> dialog.dismiss())
                .setPositiveButton("Delete", (dialog, which) ->
                        SpamStore.deleteById(requireContext(), event.id))
                .show();
    }
    private void confirmClearAll() {
        if (getContext() == null) return;

        new AlertDialog.Builder(requireContext())
                .setTitle("Clear History")
                .setMessage("This will delete all saved spam events. Continue?")
                .setNegativeButton("Cancel", (dialog, which) -> dialog.dismiss())
                .setPositiveButton("Delete All", (dialog, which) ->
                        SpamStore.clearAll(requireContext()))
                .show();
    }
    private void openMap(SpamEventEntity e) {
        if (e == null) return;

        if (e.latitude == null || e.longitude == null) {
            new AlertDialog.Builder(requireContext())
                    .setTitle("No location saved")
                    .setMessage("This event has no coordinates. Ensure Location permission is granted and Location is ON.")
                    .setPositiveButton("OK", (d, w) -> d.dismiss())
                    .show();
            return;
        }

        Bundle args = new Bundle();
        args.putLong("eventId", e.id);
        args.putString("sender", e.sender);
        args.putString("network", e.network);
        args.putInt("cellId", e.cellId == null ? -1 : e.cellId);
        args.putDouble("lat", e.latitude);
        args.putDouble("lng", e.longitude);
        args.putFloat("acc", e.accuracy == null ? -1f : e.accuracy);

        NavHostFragment.findNavController(this).navigate(R.id.mapFragment, args);
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }
}